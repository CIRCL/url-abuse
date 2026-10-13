// API page: <vt-openapi> (vitrine) renders /swagger.json.
// Vitrine is installed in static/vendor/vitrine/ by tools/3rdparty.py. Doc: doc/api/v2.md
import { configure } from './vendor/vitrine/esm/vt-openapi.js';
import './vendor/vitrine/esm/vt-http.js';
import './vendor/vitrine/esm/vt-markdown.js';

const base = new URL('./vendor/vitrine/', import.meta.url).href;
configure({
  languagesUrl: `${base}languages/`,
  syntaxThemesUrl: `${base}syntax-themes/`,
  vendorUrl: `${base}vendor/`,
});
