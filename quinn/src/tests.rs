use super::{
    read_to_end, ClientConfigBuilder, Config, Endpoint, EndpointBuilder, NewStream,
    ServerConfigBuilder,
};
use futures::{Future, Stream};
use rustls::internal::pemfile;
use slog::{Drain, Logger, KV};
use std::{fmt, fs, io, str};
use tokio;

#[test]
fn simple_echo() {
    let log = logger();
    let mut server_config = ServerConfigBuilder::default();
    let keys = {
        let mut reader = io::BufReader::new(fs::File::open("../certs/server.rsa").unwrap());
        pemfile::rsa_private_keys(&mut reader).unwrap()
    };
    let cert_chain = {
        let mut reader = io::BufReader::new(fs::File::open("../certs/server.chain").unwrap());
        pemfile::certs(&mut reader).unwrap()
    };
    server_config
        .set_certificate(cert_chain, keys[0].clone())
        .unwrap();

    let mut server = EndpointBuilder::new(Config {
        max_remote_streams_bidi: 32,
        ..Config::default()
    });
    server.logger(log.clone());
    server.listen(server_config.build());
    let (_, server_driver, server_incoming) = server.bind("[::1]:14433").unwrap();

    let mut client_config = ClientConfigBuilder::default();
    client_config
        .add_certificate_authority(&fs::read("../certs/ca.der").unwrap())
        .unwrap();
    let mut client = Endpoint::new();
    client.logger(log.clone());
    client.default_client_config(client_config.build());
    let (client, client_driver, _) = client.bind("[::1]:24433").unwrap();

    let mut runtime = tokio::runtime::current_thread::Runtime::new().unwrap();
    runtime.spawn(server_driver.map_err(|_| ()));
    runtime.spawn(client_driver.map_err(|_| ()));
    runtime.spawn(server_incoming.for_each(move |conn| {
        tokio_current_thread::spawn(conn.incoming.map_err(|_| ()).for_each(echo));
        Ok(())
    }));

    runtime
        .block_on(
            client
                .connect(&"[::1]:14433".parse().unwrap(), "localhost")
                .unwrap()
                .map_err(|_| ())
                .and_then(move |conn| {
                    let conn = conn.connection;
                    let stream = conn.open_bi();
                    stream
                        .map_err(|_| ())
                        .and_then(move |stream| {
                            tokio::io::write_all(stream, b"foo".to_vec()).map_err(|_| ())
                        })
                        .and_then(|(stream, _)| tokio::io::shutdown(stream).map_err(|_| ()))
                        .and_then(move |stream| {
                            read_to_end(stream, usize::max_value()).map_err(|_| ())
                        })
                        .and_then(move |(_, data)| {
                            assert_eq!(&data[..], b"foo");
                            conn.close(0, b"done").map_err(|_| unreachable!())
                        })
                }),
        )
        .unwrap();
}

fn echo(stream: NewStream) -> Box<dyn Future<Item = (), Error = ()>> {
    match stream {
        NewStream::Bi(stream) => Box::new(
            tokio::io::read_to_end(stream, Vec::new())
                .and_then(|(stream, data)| tokio::io::write_all(stream, data))
                .and_then(|(stream, _)| tokio::io::shutdown(stream))
                .map_err(|_| ())
                .map(|_| ()),
        ),
        _ => panic!("only bidi streams allowed"),
    }
}

fn logger() -> Logger {
    Logger::root(TestDrain.fuse(), o!())
}

struct TestDrain;

impl Drain for TestDrain {
    type Ok = ();
    type Err = io::Error;
    fn log(&self, record: &slog::Record<'_>, values: &slog::OwnedKVList) -> Result<(), io::Error> {
        let mut vals = Vec::new();
        values.serialize(&record, &mut TestSerializer(&mut vals))?;
        record
            .kv()
            .serialize(&record, &mut TestSerializer(&mut vals))?;
        println!(
            "{} {}{}",
            record.level(),
            record.msg(),
            str::from_utf8(&vals).unwrap()
        );
        Ok(())
    }
}

struct TestSerializer<'a, W>(&'a mut W);

impl<'a, W> slog::Serializer for TestSerializer<'a, W>
where
    W: io::Write + 'a,
{
    fn emit_arguments(&mut self, key: slog::Key, val: &fmt::Arguments<'_>) -> slog::Result {
        write!(self.0, ", {}: {}", key, val).unwrap();
        Ok(())
    }
}
