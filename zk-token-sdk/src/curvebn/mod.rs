pub use target_arch::*;

#[derive(Debug, PartialEq, Eq)]
pub struct PodBnPoint(pub [u8; 64]);

#[derive(Debug, PartialEq, Eq)]
pub struct PodBnScalar(pub [u8; 32]);

#[derive(Debug)]
pub enum BnError {
    FieldError(tbn::FieldError),
    GroupError(tbn::GroupError),
}

impl From<tbn::FieldError> for BnError {
    fn from(value: tbn::FieldError) -> Self {
        Self::FieldError(value)
    }
}

impl From<tbn::GroupError> for BnError {
    fn from(value: tbn::GroupError) -> Self {
        Self::GroupError(value)
    }
}

#[cfg(not(target_os = "solana"))]
mod target_arch {
    use {
        super::*,
        crate::curve_syscall_traits::{GroupOperations, PointValidation},
        tbn::{AffineG1, Fq, Fr, Group, G1},
    };

    pub fn validate_bn(point: &PodBnPoint) -> bool {
        point.validate_point()
    }

    pub fn add_bn(left_point: &PodBnPoint, right_point: &PodBnPoint) -> Option<PodBnPoint> {
        PodBnPoint::add(left_point, right_point)
    }

    pub fn subtract_bn(left_point: &PodBnPoint, right_point: &PodBnPoint) -> Option<PodBnPoint> {
        PodBnPoint::subtract(left_point, right_point)
    }

    pub fn multiply_bn(scalar: &PodBnScalar, point: &PodBnPoint) -> Option<PodBnPoint> {
        PodBnPoint::multiply(scalar, point)
    }

    impl TryFrom<&PodBnPoint> for G1 {
        type Error = BnError;
        fn try_from(value: &PodBnPoint) -> Result<Self, Self::Error> {
            let (ax_slice, ay_slice) = value.0.split_at(32);
            let fq_xa = Fq::from_slice(ax_slice)?;
            let fq_ya = Fq::from_slice(ay_slice)?;
            if fq_xa.is_zero() && fq_ya.is_zero() {
                Ok(G1::zero())
            } else {
                Ok(AffineG1::new(fq_xa, fq_ya)?.into())
            }
        }
    }

    impl TryFrom<G1> for PodBnPoint {
        type Error = BnError;
        fn try_from(value: G1) -> Result<Self, Self::Error> {
            if value.is_zero() {
                return Ok(PodBnPoint([0; 64]));
            }
            let value = AffineG1::from_jacobian(value)
                .ok_or(BnError::GroupError(tbn::GroupError::NotOnCurve))?;
            let mut result = PodBnPoint([0; 64]);
            value.x().to_big_endian(&mut result.0[0..32])?;
            value.y().to_big_endian(&mut result.0[32..64])?;
            Ok(result)
        }
    }

    impl PointValidation for PodBnPoint {
        type Point = Self;

        fn validate_point(&self) -> bool {
            G1::try_from(self).is_ok()
        }
    }

    impl GroupOperations for PodBnPoint {
        type Scalar = PodBnScalar;
        type Point = Self;

        fn add(left_point: &Self, right_point: &Self) -> Option<Self> {
            let left_point: G1 = left_point.try_into().ok()?;
            let right_point: G1 = right_point.try_into().ok()?;
            (left_point + right_point).try_into().ok()
        }

        fn subtract(left_point: &Self::Point, right_point: &Self::Point) -> Option<Self::Point> {
            let left_point: G1 = left_point.try_into().ok()?;
            let right_point: G1 = right_point.try_into().ok()?;
            (left_point - right_point).try_into().ok()
        }

        fn multiply(scalar: &Self::Scalar, point: &Self::Point) -> Option<Self::Point> {
            let point: G1 = point.try_into().ok()?;
            let scalar: Fr = Fr::from_slice(&scalar.0).ok()?;
            (point * scalar).try_into().ok()
        }
    }
}

#[cfg(test)]
mod tests {
    use tbn::{Group, G1};

    use crate::curvebn::subtract_bn;

    use super::{add_bn, multiply_bn, validate_bn, PodBnPoint, PodBnScalar};

    #[test]
    fn test_validate_bn() {
        let on_curve: PodBnPoint = G1::one().try_into().unwrap();
        assert!(validate_bn(&on_curve));

        let not_on_curve = PodBnPoint([1; 64]);
        assert!(!validate_bn(&not_on_curve));

        let zero: PodBnPoint = G1::zero().try_into().unwrap();
        assert!(validate_bn(&zero));
    }

    #[test]
    fn test_bn_add_subtract() {
        let mut rng = rand::thread_rng();
        let identity: PodBnPoint = G1::zero().try_into().unwrap();
        let point: PodBnPoint = G1::random(&mut rng).try_into().unwrap();
        assert_eq!(add_bn(&identity, &point).unwrap(), point);
        assert_eq!(add_bn(&point, &identity).unwrap(), point);
        assert_eq!(subtract_bn(&point, &identity).unwrap(), point);

        let point_a = PodBnPoint([
            33, 163, 191, 255, 99, 0, 68, 33, 116, 5, 224, 214, 42, 229, 109, 26, 49, 206, 140, 19,
            130, 179, 150, 82, 152, 172, 244, 48, 26, 104, 255, 187, 14, 203, 11, 208, 42, 18, 132,
            148, 87, 242, 207, 132, 118, 215, 226, 187, 29, 166, 133, 100, 145, 79, 73, 56, 240,
            142, 96, 182, 159, 42, 255, 62,
        ]);
        let point_b = PodBnPoint([
            17, 187, 219, 71, 240, 210, 117, 154, 49, 156, 189, 1, 92, 112, 122, 195, 164, 6, 168,
            198, 138, 239, 122, 83, 135, 250, 147, 146, 121, 176, 172, 231, 46, 160, 157, 49, 56,
            80, 178, 93, 63, 241, 176, 245, 158, 159, 93, 238, 165, 104, 166, 74, 178, 51, 192, 49,
            59, 58, 96, 98, 244, 149, 246, 190,
        ]);
        let point_c = PodBnPoint([
            0, 60, 39, 144, 191, 82, 119, 225, 211, 74, 65, 70, 180, 47, 39, 209, 248, 147, 77,
            203, 73, 158, 45, 119, 31, 174, 92, 188, 50, 206, 42, 74, 6, 76, 4, 101, 146, 176, 164,
            195, 177, 196, 46, 9, 146, 126, 88, 106, 77, 93, 74, 120, 36, 62, 47, 143, 2, 107, 5,
            8, 218, 47, 0, 167,
        ]);
        assert_eq!(add_bn(&point_a, &point_b).unwrap(), point_c);
        assert_eq!(subtract_bn(&point_c, &point_a).unwrap(), point_b);
        assert_eq!(subtract_bn(&point_c, &point_b).unwrap(), point_a);
    }

    #[test]
    fn test_bn_mul() {
        let scalar = PodBnScalar([1; 32]);
        let point_a = PodBnPoint([
            33, 163, 191, 255, 99, 0, 68, 33, 116, 5, 224, 214, 42, 229, 109, 26, 49, 206, 140, 19,
            130, 179, 150, 82, 152, 172, 244, 48, 26, 104, 255, 187, 14, 203, 11, 208, 42, 18, 132,
            148, 87, 242, 207, 132, 118, 215, 226, 187, 29, 166, 133, 100, 145, 79, 73, 56, 240,
            142, 96, 182, 159, 42, 255, 62,
        ]);
        let point_b = PodBnPoint([
            17, 187, 219, 71, 240, 210, 117, 154, 49, 156, 189, 1, 92, 112, 122, 195, 164, 6, 168,
            198, 138, 239, 122, 83, 135, 250, 147, 146, 121, 176, 172, 231, 46, 160, 157, 49, 56,
            80, 178, 93, 63, 241, 176, 245, 158, 159, 93, 238, 165, 104, 166, 74, 178, 51, 192, 49,
            59, 58, 96, 98, 244, 149, 246, 190,
        ]);

        let ax = multiply_bn(&scalar, &point_a).unwrap();
        let bx = multiply_bn(&scalar, &point_b).unwrap();

        assert_eq!(
            add_bn(&ax, &bx),
            multiply_bn(&scalar, &add_bn(&point_a, &point_b).unwrap())
        )
    }
}
