#!/bin/sh

cd /home/brendan/malrec/logs/movies
mkdir $1
cd $1
~/git/panda/scripts/rrunpack.py ~/malrec/logs/rr/${1}.rr
~/git/panda/qemu/x86_64-softmmu/qemu-system-x86_64 -m 1G -replay logs/rr/$1 -panda replaymovie
~/git/panda/qemu/panda_plugins/replaymovie/movie.sh
rm -rf replay_movie_*.ppm logs
mv replay.mp4 ../${1}.mp4
cd ..
rmdir $1
