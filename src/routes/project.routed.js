const express = require("express");
const router = express.Router();
const { getProjects, getProject, createProject, updateProject, deleteProject } =
  "./controller/Allproject.controller.js";
const { authorize, protect } = "./middleware/auth.middleware";
router.use(protect);
router.route("/").get(getProjects);
router.route("/:id").get(getProject);
router.use(authorize("admin"));
router.route("/").post(createProject);
router.route("/:id").put(updateProject).delete(deleteProject);
