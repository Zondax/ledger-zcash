use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug)]
pub struct TinData {
    pub path: [u32; 5],
    pub address: String,
    pub value: u64,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct ToutData {
    pub address: String,
    pub value: u64,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct SaplingSpendData {
    pub path: u32,
    pub address: String,
    pub value: u64,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct SaplingOutputData {
    pub ovk: Option<String>,
    pub address: String,
    pub value: u64,
    pub memo_type: u8,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct InitData {
    pub t_in: Vec<TinData>,
    pub t_out: Vec<ToutData>,
    pub s_spend: Vec<SaplingSpendData>,
    pub s_output: Vec<SaplingOutputData>,
}
