var assert = require('assert');
var expect = require('expect.js');
var cli = require('../build/cli');

describe('Cli', function() {
  describe('#create', function() {
    var inquirer;
    var args;
    var writeFile;

    beforeEach(function() {
      // Setup stubs & mocks
      inquirer = {
        prompt: function(questions, callback) {
          callback({});
        },
      };
      writeFile = function(filename, data, callback) {
        callback();
      };
    });

    it('uses the inquirer to prompt the user for answers', function(done) {
      // Arrange
      // Act
      cli.create(inquirer, args, writeFile, function() {
        // Assert
        expect(inquirer.prompt.arguments).to.be.ok();
        done();
      });
    });

    it('writes the new configuration file to disk', function(done) {
      // Arrange
      // Act
      cli.create(inquirer, args, writeFile, function() {
        // Assert
        expect(writeFile.arguments).to.be.ok();
        done();
      });
    });
  });
});
