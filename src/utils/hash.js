const { keccak256 } = require('ethers');

function mykeccak256(data) {
  return keccak256(data);
}

module.exports = { mykeccak256 };