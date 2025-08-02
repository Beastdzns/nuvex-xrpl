const { getEscrow } = require('../services/escrowService');
module.exports = (req, res) => {
  try { res.json(getEscrow(req.params.escrowId)); }
  catch (e) { res.status(404).json({ error: e.message }); }
};