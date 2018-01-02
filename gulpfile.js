'use stick';

var gulp = require('gulp');
var gulpZip = require('gulp-zip');
var gulpUnzip = require('gulp-unzip');
var spawn = require('cross-spawn');
var sf = require('split-file');
var fs = require('fs');
var path = require('path');

gulp.task('zip', ['zip:pack'], function () {
    return sf.splitFileBySize('src/design.zip', 8000000)
        .then(function (names) {
            console.log(names);
        })
        .catch(function (err) {
            console.log('Error: ', err);
        });
});

gulp.task('zip:pack', function () {
    return gulp.src('src/design/**/*')
        .pipe(gulpZip('design.zip'))
        .pipe(gulp.dest('src'));
});

gulp.task('zip:merge', function () {
    var parts = fs.readdirSync('src').map(function (file) {
        return 'src/' + file;
    }).filter(function (file) {
        return fs.statSync(file).isFile() && -1 < path.extname(file).indexOf('.sf');
    });

    return sf.mergeFiles(parts, 'src/design.zip')
        .then(function (names) {
            console.log(names);
        })
        .catch(function (err) {
            console.log('Error: ', err);
        });
});

gulp.task('unzip', ['zip:merge'], function () {
    return gulp.src('src/design.zip')
        .pipe(gulpUnzip())
        .pipe(gulp.dest('src/design'));
});

gulp.task('save', ['zip'], function (cb) {
    spawn.sync('git', ['add', '.'], {stdio: 'inherit'});
    spawn.sync('git', ['commit', '-m', 'update'], {stdio: 'inherit'});
    spawn.sync('git', ['push', 'origin', 'master:master'], {stdio: 'inherit'});
    cb();
});