import { Request, Response, NextFunction } from "express";

import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

import User from "../models/user.model";
import verificationEmail from "../common/utils/email/verificationEmail";
import welcomeEmail from "../common/utils/email/welcomeEmail";
import forgotPasswordEmail from "../common/utils/email/forgotPasswordEmail";

import { CustomRequest } from "../common/interfaces/authInterface";

const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET as string;
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET as string;

const ACCESS_TOKEN_EXPIRES_IN = process.env.ACCESS_TOKEN_EXPIRES_IN as string;
const REFRESH_TOKEN_EXPIRES_IN = process.env.REFRESH_TOKEN_EXPIRES_IN as string;

type DecodedType = {
  [key: string]: string | number;
};

export const create = async (req: Request, res: Response) => {
  try {
    const { email, phoneNumber, password } = req.body;

    if (!email || !phoneNumber || !password) {
      return res.status(400).json({
        status: "An error occured",
        message: "Incomplete Credentials",
      });
    }

    // If email already exists
    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res.status(400).json({
        status: "An error occured",
        message: "User already exists!",
      });
    }

    // hash user password
    const hashedPassword = await bcrypt.hash(password, 12);

    // create user
    await User.create({
      email,
      phoneNumber,
      password: hashedPassword,
    });

    // send verification email
    await verificationEmail(email, res);

    return res.status(201).json({
      message: "Your account was successfully created!",
    });
  } catch (error) {
    return res.status(500).json({
      status: "Error",
      message: "Internal server error",
      error,
    });
  }
};

export const verifyEmail = async (req: Request, res: Response) => {
  const { token } = req.body;

  if (!token) {
    return res.status(400).json({
      status: "Error",
      message: "Unauthorized",
    });
  }

  try {
    // find user if the verificationToken matches with the one in db
    // and if verificationEmailExpiration is less than 30 minutes

    // if all conditions are true, update the db
    const user = await User.findOneAndUpdate(
      {
        verificationToken: token,
        verificationEmailExpiration: { $gt: Date.now() },
      },
      {
        isVerified: true,
        verificationToken: "",
        verificationEmailExpiration: "",
      },
      { returnOriginal: false }
    );

    // send welcome mail
    await welcomeEmail(user?.email);

    return res.status(200).json({
      status: "Success",
      message: "User account has been verified.",
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

export const resendEmail = async (req: Request, res: Response) => {
  const { email } = req.body;

  try {
    if (!email) {
      return res.status(400).json({
        status: "Error",
        message: "Unauthorized",
      });
    }

    const user = await User.findOne({ email });

    // check if user
    if (user.isVerified) {
      return res.status(400).json({
        status: "An error occured",
        message: "User account has already been verified!",
      });
    }

    // send verification email
    await verificationEmail(email, res);

    return res.status(200).json({
      status: "Successful",
      message: "New verification mail has been sent",
    });
  } catch (error) {
    return res.status(400).json({
      status: "Error",
      message: "Email verification link is invalid or has expired.",
      error,
    });
  }
};

export const login = async (req: Request, res: Response) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res
      .status(400)
      .json({ status: "An error occured", message: "Incomplete Credentials" });
  }

  const user = await User.findOne({ email }).select("+password");

  // check if user tries to login with an unverified account
  // send new verification mail
  if (!user.isVerified) {
    await verificationEmail(user.email, res);

    return res.status(400).json({
      status: "An error occured",
      message: "User isn't verified, check email for verification link",
    });
  }

  // if account is verified
  // check if the password is correct
  const match = await bcrypt.compare(password, user.password);
  if (!user || !match) {
    return res.status(400).json({
      status: "An error occured",
      message: "Email or password is incorrect",
    });
  }

  // create tokens (access & refresh)
  const accessToken = jwt.sign({ _id: user._id }, ACCESS_TOKEN_SECRET, {
    expiresIn: ACCESS_TOKEN_EXPIRES_IN,
  });

  const refreshToken = jwt.sign({ _id: user._id }, REFRESH_TOKEN_SECRET, {
    expiresIn: REFRESH_TOKEN_EXPIRES_IN,
  });

  // update user refresh token
  await User.findOneAndUpdate({ email: user.email }, { refreshToken });

  // check if in production mode
  const isProduction = process.env.NODE_ENV === "production";

  // store token (access & refresh)
  res.cookie("access-token", accessToken, {
    secure: isProduction ? true : false,
    httpOnly: isProduction ? true : false,
    path: "/",
    sameSite: isProduction ? "none" : "lax",
    maxAge: 15 * 60 * 1000, // 15 minutes
  });

  res.cookie("refresh-token", refreshToken, {
    secure: isProduction ? true : false,
    httpOnly: isProduction ? true : false,
    path: "/",
    sameSite: isProduction ? "none" : "lax",
    maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
  });

  const { password: _, ...rest } = user.toObject();

  return res.status(200).json({ message: "Login successfully!", data: rest });
};

export const forgotPassword = async (req: Request, res: Response) => {
  const { email } = req.body;

  try {
    if (!email) {
      return res.status(400).json({
        status: "Error",
        message: "Incomplete credentials!",
      });
    }

    // send forgot password email
    await forgotPasswordEmail(email, res);

    return res.status(200).json({
      status: "Successful",
      message: "Forgot password mail has been sent",
    });
  } catch (error) {
    return res.status(500).json({
      status: "Error",
      message: "An error occured.",
      error,
    });
  }
};

export const updatePassword = async (req: Request, res: Response) => {
  const { password, token } = req.body;

  if (!password) {
    return res.status(400).json({
      status: "An error occured",
      message: "Incomplete Credentials",
    });
  }

  if (!token) {
    return res.status(400).json({
      status: "Error",
      message: "Update user password failed",
    });
  }

  try {
    // hash user password
    const hashedPassword = await bcrypt.hash(password, 12);

    // find user if the forgotPasswordToken matches with the one in db
    // and if forgotPasswordEmailExpiration is less than 30 minutes

    // if all conditions are true, update the db
    const user = await User.findOneAndUpdate(
      {
        forgotPasswordToken: token,
        forgotPasswordEmailExpiration: { $gt: Date.now() },
      },
      {
        forgotPasswordToken: "",
        forgotPasswordEmailExpiration: "",
        password: hashedPassword,
      },
      { returnOriginal: false }
    );

    // check if user doesn't exist
    if (!user) {
      return res.status(400).json({
        status: "An error occured",
        message: "User doesn't exist! Update user password failed",
      });
    }

    return res.status(200).json({
      status: "Successful",
      message: "Password updated successfully!",
    });
  } catch (error) {
    return res.status(500).json({
      status: "Error",
      message: "Internal server error",
    });
  }
};

export const logout = async (req: Request, res: Response) => {
  // check if in production mode
  const isProduction = process.env.NODE_ENV === "production";

  res.clearCookie("access-token", {
    secure: isProduction ? true : false,
    httpOnly: isProduction ? true : false,
    path: "/",
    sameSite: isProduction ? "none" : "lax",
    maxAge: -1,
  });

  res.clearCookie("refresh-token", {
    secure: isProduction ? true : false,
    httpOnly: isProduction ? true : false,
    path: "/",
    sameSite: isProduction ? "none" : "lax",
    maxAge: -1,
  });

  return res.status(200).json({
    status: "Success",
    message: "User successfully logged out",
  });
};

export const protect = async (
  req: CustomRequest,
  res: Response,
  next: NextFunction
): Promise<Response | void> => {
  const accessToken = req.cookies["access-token"];
  const refreshToken = req.cookies["refresh-token"];

  // check if refresh token doesn't exist
  if (!refreshToken) {
    return res.status(403).json({
      message: "Unauthorized",
    });
  }

  // check decoded access token against the database
  // to ensure that the associated user exists and
  // is authorized to access the protected resource.

  const handleDecoded = async (decoded: DecodedType) => {
    const user = await User.findOne({ _id: decoded._id }).select(
      "+refreshToken"
    );

    // if user doesn't exist
    if (!user) {
      return res.status(400).json({
        status: "Error",
        message: "Unauthorized",
      });
    }

    // if refresh token is invalid
    if (user.refreshToken !== refreshToken) {
      return res
        .status(400)
        .json({ status: "Error", message: "Unauthorized - Invalid token" });
    }

    // if user changed password

    const { refreshToken: _, ...rest } = user;

    return rest;
  };

  try {
    // verify access token
    const decoded = jwt.verify(accessToken, ACCESS_TOKEN_SECRET) as DecodedType;

    const currentUser = await handleDecoded(decoded);

    req.user = currentUser;
  } catch (error) {
    //  if error in verifying access token
    const castedError = error as Error;
    if (
      castedError.name === "JsonWebTokenError" ||
      (castedError.name === "TokenExpiredError" && refreshToken)
    ) {
      try {
        // verify refreshToken
        const decoded = jwt.verify(
          refreshToken,
          REFRESH_TOKEN_SECRET
        ) as DecodedType;

        const decodedUser = await handleDecoded(decoded);
        console.log("Decoded", decodedUser);

        req.user = decodedUser;

        if (decodedUser && "_id" in decodedUser) {
          const currentUser = decodedUser;

          // create new access token
          const accessToken = jwt.sign(
            { _id: currentUser._id },
            ACCESS_TOKEN_SECRET,
            {
              expiresIn: ACCESS_TOKEN_EXPIRES_IN,
            }
          );

          // check if in production mode
          const isProduction = process.env.NODE_ENV === "production";

          // store token (access & refresh)
          return res.cookie("access-token", accessToken, {
            secure: isProduction ? true : false,
            httpOnly: isProduction ? true : false,
            path: "/",
            sameSite: isProduction ? "none" : "lax",
            maxAge: 15 * 60 * 1000, // 15 minutes
          });
        }
      } catch (error) {
        return res
          .status(400)
          .json({ status: "Error", message: "Unauthorized" });
      }
    }
  }

  next();
};
