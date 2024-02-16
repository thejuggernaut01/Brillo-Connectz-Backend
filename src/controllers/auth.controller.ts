import { Request, Response, NextFunction } from "express";

import crypto from "crypto";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

import User from "../models/user.model";
import verificationEmail from "../common/utils/email/verificationEmail";
import welcomeEmail from "../common/utils/email/welcomeEmail";

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

    // generate verification token and save user to the database with isVerified set to false
    crypto.randomBytes(32, async (err: Error, buffer: any) => {
      if (err) {
        return res.status(400).json({
          status: "Error",
          message: "An error occured",
        });
      }

      // convert the randomBytes buffer to hex string
      const token = buffer.toString("hex");

      // create user
      await User.create({
        email,
        phoneNumber,
        password: hashedPassword,
      });

      // send verification email
      await verificationEmail(email, token);

      return res.status(201).json({
        message: "Your account was successfully created!",
      });
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
  const token = req.query.token;

  if (!token) {
    return res.status(400).json({
      status: "Error",
      message: "Unauthorized",
    });
  }

  try {
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

    console.log(user);

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

export const login = async (req: Request, res: Response) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res
      .status(400)
      .json({ status: "An error occured", message: "Incomplete Credentials" });
  }

  const user = await User.findOne({ username }).select("+password");

  // check if password is correct
  const match = await bcrypt.compare(password, user.password);
  if (!user || !match) {
    return res.status(400).json({
      status: "An error occured",
      message: "Username or password is incorrect",
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

export const protect = async (
  req: Request,
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

    await handleDecoded(decoded);
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
          res.cookie("access-token", accessToken, {
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
