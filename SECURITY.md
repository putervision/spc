# Security Policy

`@putervision/spc` (Space Proof Code) enforces static code analysis and security rules across safety-critical systems. We take security and vulnerability reporting seriously.

---

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| v1.5.x  | :white_check_mark: |
| v1.4.x  | :white_check_mark: |
| v1.3.x  | :white_check_mark: |
| v1.2.x  | :white_check_mark: |
| v1.1.x  | :white_check_mark: |
| < 1.1.0 | :x:                |

---

## Reporting a Vulnerability

If you discover a security vulnerability or false-negative bypass in `@putervision/spc` (e.g., AST regex bypass, unsafe input execution, or CLI path traversal exposure), please report it responsibly:

1. **Do NOT open a public GitHub issue.**
2. Send an email to **security@putervision.com** or report via GitHub Security Advisory.
3. Include detailed steps to reproduce, sample code snippet, and impact analysis.

### Our Commitment
- We will acknowledge receipt of your vulnerability report within **48 hours**.
- We will provide a regular status update until the vulnerability is addressed.
- A patched release will be published to npm promptly once verified.

---

## Security Architecture & Local Privacy

`@putervision/spc` runs 100% locally on your machine or CI/CD runner:
- **Zero External Dependencies**: 100% native Node.js regex AST parsing. No third-party npm package supply chain risks.
- **Zero Telemetry / Network Calls**: Code scanning is completely isolated and local. No source code or scan telemetry is ever transmitted over the network.

---

## License & Disclaimer

Developed and maintained by [PuterVision](https://putervision.com). Released under the [MIT License](LICENSE).

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
