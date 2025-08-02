const express = require('express');
const createDst = require('../controllers/createDstController');
const fund = require('../controllers/fundController');
const withdraw = require('../controllers/withdrawController');
const cancel = require('../controllers/cancelController');
const rescue = require('../controllers/rescueController');
const getEscrow = require('../controllers/getEscrowController');

const router = express.Router();
router.post('/create-dst', createDst);
router.post('/:escrowId/fund', fund);
router.post('/:escrowId/withdraw', withdraw);
router.post('/:escrowId/cancel', cancel);
router.post('/:escrowId/rescue', rescue);
router.get('/:escrowId', getEscrow);

module.exports = () => router;