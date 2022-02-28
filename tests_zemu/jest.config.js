module.exports = {
  preset: 'ts-jest',
  modulePaths: ["<rootDir>/src", "<rootDir>/tests"],
  globalSetup: "<rootDir>/globalsetup.js",
 testEnvironment: "node",
};
