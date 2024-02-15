import express from "express";

import { getMovie, getMovies, addMovie } from "@/controllers/movie.controller";

const router = express.Router();

router.get("/movies", getMovies);

router.get("/movies/:movieId", getMovie);

router.post("/add-movie", addMovie);

export default router;
