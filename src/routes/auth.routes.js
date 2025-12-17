import { Router } from "express";
import {
  registerUser,
  login,
  logout,
  verifyEmail,
  refreshAccessToken,
  resetForgetPassword,
  forgetPasswordRequest,
  getCurrentUser,
  changeCurrentPassword,
  resendEmailVerification,
} from "../controllers/auth.controller.js";
import {
  userRegisterValidator,
  userLoginValidator,
  userForgetPasswordValidator,
  userChangeCurrentPasswordValidator,
} from "../validators/index.js";
import { validate } from "../middleware/validator.middleware.js";
import { verifyJWT } from "../middleware/auth.middleware.js";
const router = Router();
//unsecures routes
router.route("/register").post(userRegisterValidator(), validate, registerUser);
router.route("/login").post(userLoginValidator(), validate, login);
router.route("/verify-email/:verificationToken").get(verifyEmail);
router.route("/refresh-token").post(refreshAccessToken);
router
  .route("/forget-Password")
  .post(userForgetPasswordValidator(), validate, forgetPasswordRequest);
router
  .route("/reset-password/:resetToken")
  .post(userForgetPasswordValidator(), validate, resetForgetPassword);
//secured routes
router.route("/logout").post(verifyJWT, logout);
router.route("/current-user").post(verifyJWT, getCurrentUser);
router
  .route("/change-password")
  .post(
    verifyJWT,
    userChangeCurrentPasswordValidator(),
    validate,
    changeCurrentPassword,
  );
router
  .route("/resend-email-verification")
  .post(verifyJWT, resendEmailVerification);
export default router;
