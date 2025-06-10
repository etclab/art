// The art package implements the Asynchronous Ratcheting Tree protocol from
// the [paper]:
//
//  Katriel Cohn-Gordon, Cas Cremers, Luke  Garratt, Jon Millican, and Kevin Milner.
//  "On Ends-to-Ends Encryption: Asynchronous Group Messaging with Strong Security Guarantees."
//  In ACM Conference on Computer and Communications Security (CCS), 2018.
//
// ART is type of continuous group key agreement (CGKA) protocol that uses a
// Diffie-Hellman binary tree as its main datastucture for establishing a group
// key.  ART inspired the protocols that would become the Messaging Layer
// Security IETF standard.

// This package implements the basic protocol as described in Section 5 of that
// paper.
//
// [paper]: https://dl.acm.org/doi/10.1145/3243734.3243747
package art
