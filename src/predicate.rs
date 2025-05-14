// A predicate is a collection of linear combinations of g_0 = s_1 * g_1 + s_2 * g_2 + ...
// When building a predicate, the points are all available as are any public scalars.
// Private scalars make up the witness. The witness is not known when building the predicate, and
// is never known to the prover.
//
// OONI
//
// #[derive(Attributes, Clone, Debug)]
// struct OoniAttributes {
//     /// A secret key held by the client for the purpose of deriving context-specific pseudonyms.
//     /// This value is private during issuance, and used during presentation to derive pseudonyms.
//     #[rkvc(label = "OoniAttributes::pseudonym_key")]
//     pub pseudonym_key: Scalar,
//     /// An creation time for the credential. Public and chosen by the server during issuance, and
//     /// private thereafter. The client must prove during presentation that there credential is at
//     /// least a certain age.
//     pub created_at: u64,
//     /// A count of the number of measurements uploaded by this client. Intialized to zero during
//     /// issuance and incremented by one for each provided measurement.
//     pub measurement_count: u64,
//     /// A bit set to true if the client is a trusted party. Set by the server during presentation,
//     /// and can be optionally revealed to bypass other predicate checks if true.
//     pub is_trusted: bool,
// }
//
// Auth predicate (min_age: F, min_measurement_count: F, now: F, pseudonym_ctx: G, pseudonym: G)
//
// * Allocate A = AttributeArray<ScalarVar, OoniAttributes>
// * mac_presentation is valid over A.
// * A.measurement_count - min_measurement_count >= 0
// * A.created_at <= now - min_age
// * pseudonym == A.pseudonym_key * pseudonym_ctx

// In the prover,
// * the witness values are given during allocation of scalar vars.
// * points are computed in the course of the predicate and become part of the proof. A point is
//   allocated when it is contrained to be equal to a linear combinations of previously allocated
//   point and scalar variables. Any G that is used in a linear combination results in the allocation
//   of a point.
//
// In the verifier,
// * the witness values are not supplied, so the scalar vars are simply labels.
// * all point vars have values up-front rather than only at the end.
