const { getDefaultConfig } = require('expo/metro-config');

const config = getDefaultConfig(__dirname);

// Enable package exports support (required for @noble packages)
config.resolver.unstable_enablePackageExports = true;

module.exports = config;
