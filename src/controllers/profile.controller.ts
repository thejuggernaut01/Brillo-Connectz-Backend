import { Response } from "express";
import User from "../models/user.model";
import { CustomRequest } from "../common/interfaces/authInterface";

export const getProfile = async (req: CustomRequest, res: Response) => {
  const currentUserId = req.user?._id;

  try {
    const user = await User.findOne({ _id: currentUserId });

    return res.status(200).json({
      status: "Success",
      data: user,
    });
  } catch (error) {
    return res.status(400).json({
      status: "Error",
      message: "Email verification link is invalid or has expired.",
      error,
    });
  }
};
