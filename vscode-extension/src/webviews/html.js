'use strict';

/**
 * Escape a value inserted into an HTML attribute or text node.
 *
 * @param {unknown} value
 * @returns {string}
 */
function escapeAttribute(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;');
}

/**
 * Serialize a value for an inline application/json script.
 *
 * Escaping `<`, `>`, and `&` prevents a value from closing the script element
 * while keeping the payload valid JSON. U+2028/U+2029 are escaped for older
 * JavaScript parsers.
 *
 * @param {unknown} value
 * @returns {string}
 */
function serializeStateForScript(value) {
  return JSON.stringify(value)
    .replaceAll('<', '\\u003c')
    .replaceAll('>', '\\u003e')
    .replaceAll('&', '\\u0026')
    .replaceAll('\u2028', '\\u2028')
    .replaceAll('\u2029', '\\u2029');
}

module.exports = { escapeAttribute, serializeStateForScript };
