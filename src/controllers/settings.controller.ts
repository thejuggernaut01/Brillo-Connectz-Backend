import { Request, Response } from "express";
import bcrypt from "bcryptjs";

import User from "../models/user.model";
import { CustomRequest } from "../common/interfaces/authInterface";

export const changePassword = async (req: CustomRequest, res: Response) => {
  const { password } = req.body;

  if (!password) {
    return res.status(400).json({
      status: "Error",
      message: "Incomplete credentials",
    });
  }

  const currentUserId = req.user?._doc?._id;
  try {
    const hashedPassword = await bcrypt.hash(password, 12);

    await User.findOneAndUpdate(
      { _id: currentUserId },
      {
        password: hashedPassword,
      }
    );

    return res.status(200).json({
      status: "Success",
      message: "Password changed successfully",
    });
  } catch (error) {
    return res.status(500).json({
      status: "Error",
      message: "Internal server error",
      error,
    });
  }
};

export const updateUsername = async (req: CustomRequest, res: Response) => {
  const { username } = req.body;

  if (!username) {
    return res.status(400).json({
      status: "An error occured",
      message: "Incomplete Credentials",
    });
  }

  const currentUserId = req.user?._doc?._id;
  console.log(currentUserId);

  try {
    await User.findOneAndUpdate(
      { _id: currentUserId },
      {
        username: username,
      }
    );

    return res.status(200).json({
      status: "Success",
      message: "Username updated successfully",
    });
  } catch (error) {
    return res.status(500).json({
      status: "Error",
      message: "Internal server error",
      error,
    });
  }
};

export const updateEmail = async (req: Request, res: Response) => {
  const { email } = req.body;
};
