use jubjub::{AffineNielsPoint, AffinePoint, Fq};

pub const SPENDING_KEY_BASE: AffineNielsPoint = AffinePoint::from_raw_unchecked(
    Fq::from_raw([
        0x47bf46920a95a753,
        0xd5b9a7d3ef8e2827,
        0xd418a7ff26753b6a,
        0x0926d4f32059c712,
    ]),
    Fq::from_raw([
        0x305632adaaf2b530,
        0x6d65674dcedbddbc,
        0x53bb37d0c21cfd05,
        0x57a1019e6de9b675,
    ]),
)
.to_niels();

pub const PROVING_KEY_BASE: AffineNielsPoint = AffinePoint::from_raw_unchecked(
    Fq::from_raw([
        0x3af2dbefb96e2571,
        0xadf2d038f2fbb820,
        0x704303f1e8906081,
        0x1457a50231cde2df,
    ]),
    Fq::from_raw([
        0x467af9f7e05de8e7,
        0x50df51eaf5a149d2,
        0xdec901840f4948cc,
        0x54b6d10718df2a7a,
    ]),
)
.to_niels();
