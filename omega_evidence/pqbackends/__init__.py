# Copyright 2026 Roberto Locatelli
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
omega_evidence.pqbackends — pluggable post-quantum signature backends.

The toolkit ships NO home-grown PQ cryptography: writing ML-DSA/SLH-DSA by hand
would be slow, side-channel-unsafe, and hard to validate. Instead a backend is
adopted only through a KAT gate (`register_pq_backend`) that refuses any verifier
which does not reproduce known-answer test vectors AND reject tampered ones — so a
broken or fake backend can never be trusted. A real backend (e.g. a `cryptography`
build with SLH-DSA, or liboqs) is wired in by `slhdsa.try_load()` / `mldsa`.
"""

from .gate import register_pq_backend  # noqa: F401

__all__ = ["register_pq_backend"]
