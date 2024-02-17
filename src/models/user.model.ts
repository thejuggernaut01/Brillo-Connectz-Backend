import mongoose from "mongoose";

const UserSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      unique: true,
      required: [true, "Email is required"],
    },
    phoneNumber: {
      type: String,
      unique: true,
      required: [true, "Phone number is required"],
    },
    password: {
      type: String,
      required: [true, "Password is required"],
      select: false,
    },
    username: String,

    refreshToken: { type: String, select: false },
    isVerified: { type: Boolean },
    verificationEmailExpiration: { type: Date, select: false },
    verificationToken: { type: String, select: false },
    forgotPasswordEmailExpiration: { type: Date, select: false },
    forgotPasswordToken: { type: String, select: false },
  },
  { timestamps: true }
);

const User = mongoose.model("User", UserSchema);

export default User;
