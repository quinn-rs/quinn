use proc_macro::TokenStream;
use syn::__private::ToTokens;
use syn::{
    parse_macro_input, Error, Item, ItemConst, ItemEnum, ItemExternCrate, ItemFn, ItemMacro2,
    ItemMod, ItemStatic, ItemStruct, ItemTrait, ItemTraitAlias, ItemType, ItemUnion, ItemUse,
    Visibility,
};

/// A modified version of the macro from https://github.com/danielhenrymantilla/visibility.rs
/// (https://crates.io/crates/visibility). This version of the macro will automatically apply
/// struct visibility to its fields. This is useful for testing, since struct construction
/// requires that all fields are visible at the call site.
#[proc_macro_attribute]
pub fn make(attrs: TokenStream, input: TokenStream) -> TokenStream {
    let visibility: Visibility = parse_macro_input!(attrs);
    let mut input: Item = parse_macro_input!(input);

    match input {
        Item::Const(ItemConst { ref mut vis, .. }) => *vis = visibility,
        Item::Enum(ItemEnum { ref mut vis, .. }) => *vis = visibility,
        Item::ExternCrate(ItemExternCrate { ref mut vis, .. }) => *vis = visibility,
        Item::Fn(ItemFn { ref mut vis, .. }) => *vis = visibility,
        // Item::ForeignMod(ItemForeignMod { ref mut vis, .. }) => *vis = visibility,
        // Item::Impl(ItemImpl { ref mut vis, .. }) => *vis = visibility,
        // Item::Macro(ItemMacro { ref mut vis, .. }) => *vis = visibility,
        Item::Macro2(ItemMacro2 { ref mut vis, .. }) => *vis = visibility,
        Item::Mod(ItemMod { ref mut vis, .. }) => *vis = visibility,
        Item::Static(ItemStatic { ref mut vis, .. }) => *vis = visibility,
        Item::Struct(ItemStruct {
            ref mut vis,
            ref mut fields,
            ..
        }) => {
            // Apply the visibility changes to all fields as well as the struct, itself.
            *vis = visibility.clone();
            for field in fields {
                field.vis = visibility.clone();
            }
        }
        Item::Trait(ItemTrait { ref mut vis, .. }) => *vis = visibility,
        Item::TraitAlias(ItemTraitAlias { ref mut vis, .. }) => *vis = visibility,
        Item::Type(ItemType { ref mut vis, .. }) => *vis = visibility,
        Item::Union(ItemUnion { ref mut vis, .. }) => *vis = visibility,
        Item::Use(ItemUse { ref mut vis, .. }) => *vis = visibility,
        // Item::Verbatim(TokenStream { ref mut vis, .. }) => *vis = visibility,
        _ => {
            return Error::new_spanned(&input, "Cannot override the `#[visibility]` of this item")
                .to_compile_error()
                .into()
        }
    }

    input.into_token_stream().into()
}
