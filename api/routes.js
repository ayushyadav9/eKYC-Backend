const express = require("express");
const router = express.Router();
const passport = require("passport");
const { notFound, home } = require("./controllers/home");
const {
  register,
  login,
  getClientData,
  getBankList,
  request,
  updateRecord,
  updateSocket,
  getSocket,
  addApprovedClient,
  getApprovedClients,
  checkUser,
  updateRecordFromClient
} = require("./controllers/userController");

router.get("/", home);
router.post("/register", register);
router.post("/login", login);
router.get("/getClientData",passport.authenticate("jwt", { session: false }),getClientData);
router.get("/getBankList", passport.authenticate("jwt", { session: false }), getBankList);
router.post("/request", passport.authenticate("jwt", { session: false }), request);
router.post("/updateRecord", updateRecord);
router.post("/updateRecordFromClient",passport.authenticate("jwt", { session: false }), updateRecordFromClient);
router.post("/updateSocket", passport.authenticate("jwt", { session: false }), updateSocket);
router.post("/getSocket", getSocket);
router.post("/addApprovedClient", addApprovedClient);
router.post("/getApprovedClients", getApprovedClients);
router.post("/checkUser", checkUser);


router.get("*", notFound);

module.exports = router;
