import { Request, Response } from "express";
import MovieModel from "../models/movie.model";

export const getMovies = async (req: Request, res: Response) => {
  try {
    const movies = await MovieModel.find();

    // if there's no movies in database
    if (!movies) {
      return res.status(404).json({
        status: "Not found",
        message: "movies not found!",
        data: [],
      });
    }

    return res.status(200).json({
      status: "Successful",
      message: "All movies fetched sucessfully",
      data: movies,
    });
  } catch (error) {
    const castedError = error as Error;
    const { stack: _, ...rest } = castedError;

    return res.status(500).json({
      status: "Error",
      message: "An error occured!",
      error: rest,
    });
  }
};

export const getMovie = async (req: Request, res: Response) => {
  const movieId = req.params.movieId;

  try {
    // if movie doesn't exist
    if (!movieId) {
      return res.status(404).json({
        status: "Error",
        message: "Movie not dound",
      });
    }

    const movie = await MovieModel.findOne({ movieId });

    // if the movie is not found in the database
    if (!movie) {
      return res.status(404).json({
        status: "",
        message: "movie not found!",
      });
    }

    return res.status(200).json({
      status: "Successful",
      message: "All movies fetched sucessfully",
      data: movie,
    });
  } catch (error) {
    const castedError = error as Error;
    const { stack: _, ...rest } = castedError;

    return res.status(500).json({
      status: "Error",
      message: "An error occured!",
      error: rest,
    });
  }
};

export const addMovie = async (req: Request, res: Response) => {
  const {
    title,
    desc,
    price,
    pg,
    date,
    duration,
    quality,
    year,
    rating,
    genre,
  } = req.body;

  if (
    !title ||
    !desc ||
    !price ||
    !pg ||
    !date ||
    !duration ||
    !quality ||
    !year ||
    !rating ||
    !genre
  ) {
    return res.status(422).json({
      status: "Error",
      message: "Incomplete data!",
    });
  }

  const data = await MovieModel.create({
    movieId: title?.split(" ").join("-"),
    ...req.body,
  });

  return res.status(201).json({
    message: "Movie upload was successful!",
  });
};
