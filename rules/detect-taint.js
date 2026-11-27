/**
 * Detects source-to-sink injection flows across function boundaries.
 */

'use strict';

const { createTaintRule } = require('../utils/taint-tracker');

module.exports = createTaintRule();
