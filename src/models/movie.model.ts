import mongoose from "mongoose";

const MovieSchema = new mongoose.Schema({
  movieId: { type: String, required: [true, "movie id is required"] },
  title: { type: String, required: [true, "title is required"] },
  desc: { type: String, required: [true, "description is required"] },
  price: { type: Number, required: [true, "price is required"] },
  pg: { type: String, required: [true, "pg is required"] },
  date: { type: Date, required: [true, "date is required"] },
  duration: { type: Number, required: [true, "duration is required"] },
  quality: { type: String, required: [true, "quality is required"] },
  year: { type: Number, required: [true, "year is required"] },
  rating: { type: Number, required: [true, "rating is required"] },
  genre: { type: [String], required: [true, "genre is required"] },
});

const MovieModel = mongoose.model("Movie", MovieSchema);

export default MovieModel;
