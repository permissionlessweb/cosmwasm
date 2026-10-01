;; Final SIMD encoding: 0xFD 0xFC is i32x4.trunc_sat_f64x2_s_zero.
;; Lane 0 of trunc(1.9, -2.0) is 1.
(module
  (func (export "trunc") (result i32)
    (i32x4.extract_lane 0
      (i32x4.trunc_sat_f64x2_s_zero
        (v128.const f64x2 1.9 -2.0))))
)
