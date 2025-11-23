source ../../env/bin/activate

RUN_NAME=run1
log=$1

. env.sh

python guard.py --framework together --log-file $log.guard --input-file $log
