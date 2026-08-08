# Vendored front-end libraries

These are **committed locally** so the dashboard is fully self-contained and works
**air-gapped** — no runtime CDN dependency, and `script-src` in the page CSP is
`'self'` only (no remote host allowed). A pentest dashboard should never have to
reach out to a third-party CDN to render.

| File | Package (source spec) | Upstream |
|------|-----------------------|----------|
| `mermaid.min.js`   | `mermaid@10`          | https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js |
| `marked.min.js`    | `marked@9`            | https://cdn.jsdelivr.net/npm/marked@9/marked.min.js |
| `cytoscape.min.js` | `cytoscape@3.30.2`    | https://cdn.jsdelivr.net/npm/cytoscape@3.30.2/dist/cytoscape.min.js |

## SHA-256 (integrity of the committed bytes)
```
mermaid.min.js    eda3a0ad572bbe69a318c1be0163e8233dd824f3f12939e5168feba207767151
marked.min.js     6002af63485b043fa60ddaba1b34363b98d2a8b2c63b607004f3a2405a8a053a
cytoscape.min.js  83e8c54a6bec655bfd81df07df605649c268af69aeca67a5ea2da54ea42dac81
```

## Re-vendor (only when deliberately upgrading)
```bash
cd dashboard/js/vendor
curl -sSLo mermaid.min.js   https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js
curl -sSLo marked.min.js    https://cdn.jsdelivr.net/npm/marked@9/marked.min.js
curl -sSLo cytoscape.min.js https://cdn.jsdelivr.net/npm/cytoscape@3.30.2/dist/cytoscape.min.js
# then update the SHA-256 table above
```
