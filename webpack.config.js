const path = require('path');

module.exports = {
  entry: './yellow-integration.js',
  output: {
    filename: 'yellow-bundle.js',
    path: path.resolve(__dirname, '.'),
    library: 'YellowIntegration',
    libraryTarget: 'window'
  },
  mode: 'development',
  resolve: {
    fallback: {
      "buffer": require.resolve("buffer/"),
      "crypto": require.resolve("crypto-browserify"),
      "stream": require.resolve("stream-browserify"),
      "util": require.resolve("util/"),
      "process": require.resolve("process/browser")
    }
  }
};
