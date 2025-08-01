const { rescue } = require('../services/escrowService');
module.exports = async (req, res) => {
  const { callerAddress, amount } = req.body;
  try { res.json(await rescue(req.params.escrowId, callerAddress, amount)); }
  catch (e) { res.status(500).json({ error: e.message }); }
};