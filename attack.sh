#!/bin/sh

VICTIM=./victim.out
ATTACK=./attack.out
PRE_WAIT = 0.07

echo "Start the victim process"; 
${VICTIM}
echo "Finsh!"
VICTIM_PID=$!

#wait the vitim do necessary work
sleep ${PRE_WAIT}

echo "Start the attack process"; 
${ATTACK}
ATTACK_PID=$!

trap "echo 'Received signal'; kill -TERM ${Attack_PID} ${VICTIM_PID}" \
    SIGINT SIGQUIT

wait ${ATTACK_PID}
wait ${VICTIM_PID}
