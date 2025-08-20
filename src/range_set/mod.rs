// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

mod array_range_set;
mod btree_range_set;
#[cfg(test)]
mod tests;

pub(crate) use array_range_set::ArrayRangeSet;
pub(crate) use btree_range_set::RangeSet;
