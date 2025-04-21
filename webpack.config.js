const path = require('path');

module.exports = {
  entry: './src/index.ts',
  module: {
    rules: [
      {
        test: /\.tsx?$/,
        use: 'ts-loader',
        exclude: /node_modules/
      }
    ]
  },
  resolve: {
    extensions: ['.tsx', '.ts', '.js'],
    fallback: {
        "crypto": require.resolve("crypto-browserify"),
        "buffer": require.resolve("buffer/"),
        "stream": require.resolve("stream-browserify"),
        "vm": require.resolve("vm-browserify"),
    }
  },
  output: {
    //filename: 'bundle.js',
    path: path.resolve(__dirname, 'dist/min'),
    library: 'WavesCrypto',
    libraryTarget: 'umd',
    filename: 'waves-lib-crypto.js'
  }
};

