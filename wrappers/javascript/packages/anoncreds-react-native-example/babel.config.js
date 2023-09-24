const path = require('path')

const anoncredsReactNative = require('../anoncreds-react-native/package.json')
const anoncredsShared = require('../anoncreds-shared/package.json')

module.exports = function (api) {
  api.cache(true)
  return {
    presets: ['babel-preset-expo'],
    plugins: [
      [
        'module-resolver',
        {
          extensions: ['.tsx', '.ts', '.js', '.json'],
          alias: {
            [anoncredsReactNative.name]: path.join(__dirname, '../anoncreds-react-native', anoncredsReactNative.source),
            [anoncredsShared.name]: path.join(__dirname, '../anoncreds-shared', anoncredsShared.source)
          }
        }
      ]
    ]
  }
}
