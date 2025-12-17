const Project = require("../models/Project");
const ErrorResponse = require("../utils/errorResponse"); // Your existing error util
const asyncHandler = require("../middleware/async"); // Your async wrapper

// GET /api/v1/projects - List projects user can access
exports.getProjects = asyncHandler(async (req, res, next) => {
  const query = {
    $or: [{ admin: req.user.id }, { members: req.user.id }],
  };

  const projects = await Project.find(query)
    .populate("admin", "name email")
    .populate("members", "name email")
    .sort("-createdAt")
    .lean(); // Faster for read-only

  res.status(200).json({
    success: true,
    count: projects.length,
    data: projects,
  });
});
// GET /api/v1/projects/:id
exports.getProject = asyncHandler(async (req, res, next) => {
  const project = await Project.findById(req.params.id)
    .populate("admin", "name email")
    .populate("members", "name email");

  if (!project) {
    return next(
      new ErrorResponse(`Project not found with id ${req.params.id}`, 404),
    );
  }

  // Check if user has access
  const hasAccess =
    project.admin._id.equals(req.user.id) ||
    project.members.some((member) => member._id.equals(req.user.id));

  if (!hasAccess) {
    return next(
      new ErrorResponse("Not authorized to access this project", 403),
    );
  }

  res.status(200).json({
    success: true,
    data: project,
  });
});
// POST /api/v1/projects
exports.createProject = asyncHandler(async (req, res, next) => {
  const { name, description } = req.body;

  // Check if user is Admin
  if (req.user.role !== "Admin") {
    return next(new ErrorResponse("Only Admins can create projects", 403));
  }

  const project = await Project.create({
    name,
    description,
    admin: req.user.id,
    members: [req.user.id], // Admin is first member
    memberCount: 1,
  });

  const populatedProject = await Project.findById(project._id)
    .populate("admin", "name email")
    .populate("members", "name email");

  res.status(201).json({
    success: true,
    data: populatedProject,
  });
});
// PUT /api/v1/projects/:id
exports.updateProject = asyncHandler(async (req, res, next) => {
  let project = await Project.findById(req.params.id);

  if (!project) {
    return next(
      new ErrorResponse(`Project not found with id ${req.params.id}`, 404),
    );
  }

  // Only admin can update
  if (!project.admin._id.equals(req.user.id)) {
    return next(
      new ErrorResponse("Not authorized to update this project", 403),
    );
  }

  project = await Project.findByIdAndUpdate(req.params.id, req.body, {
    new: true, // Return updated document
    runValidators: true,
  })
    .populate("admin", "name email")
    .populate("members", "name email");

  res.status(200).json({
    success: true,
    data: project,
  });
});
// DELETE /api/v1/projects/:id
exports.deleteProject = asyncHandler(async (req, res, next) => {
  const project = await Project.findById(req.params.id);

  if (!project) {
    return next(
      new ErrorResponse(`Project not found with id ${req.params.id}`, 404),
    );
  }

  if (!project.admin._id.equals(req.user.id)) {
    return next(
      new ErrorResponse("Not authorized to delete this project", 403),
    );
  }

  await Project.findByIdAndDelete(req.params.id);

  res.status(200).json({
    success: true,
    data: {},
  });
});
