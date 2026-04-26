#!/bin/bash

OUTPUT_FILE="results3.csv"

echo "vec_size,value_type,encrypt_ms,total_ms,ciphertext_bytes,result" > $OUTPUT_FILE

VEC_SIZES=(8 32 128 512)
VALUE_TYPES=("CONST")

REPEAT=1

for vec in "${VEC_SIZES[@]}"; do
  for valtype in "${VALUE_TYPES[@]}"; do

    echo "Running test: vec_size=$vec value_type=$valtype"

    for ((r=1; r<=REPEAT; r++)); do

      TMP1=$(mktemp)
      TMP2=$(mktemp)
      TMP3=$(mktemp)

      ./multiclient --vec_size $vec --value_type $valtype --mode submit > $TMP1 2>&1 &
      PID1=$!
      ./multiclient --vec_size $vec --value_type $valtype --mode submit > $TMP2 2>&1 &
      PID2=$!
      ./multiclient --vec_size $vec --value_type $valtype --mode submit > $TMP3 2>&1 &
      PID3=$!

      wait $PID1
      wait $PID2
      wait $PID3

      # Use client 1's output — all three get the same result, and client 1
      # is the one that blocks longest so it best reflects true latency
      LINE=$(grep "vector_size=" $TMP1)

      if [ -z "$LINE" ]; then
        echo "WARNING: no output from client on repeat $r, skipping"
        rm $TMP1 $TMP2 $TMP3
        continue
      fi

      # Format: vector_size=8,mode=submit,encrypt_ms=1.2,total_ms=5.6,ciphertext_bytes=1234,result=[...]
      # Fields after splitting on [=,]:
      #  1=vector_size 2=8 3=mode 4=submit 5=encrypt_ms 6=<val> 7=total_ms 8=<val> 9=ciphertext_bytes 10=<val> 11=result 12=<val>
      vec_size=$(echo "$LINE"    | awk -F'[=,]' '{print $2}')
      encrypt_ms=$(echo "$LINE"  | awk -F'[=,]' '{print $6}')
      total_ms=$(echo "$LINE"    | awk -F'[=,]' '{print $8}')
      bytes=$(echo "$LINE"       | awk -F'[=,]' '{print $10}')
      # result=[...] — grab everything after "result="
      result=$(echo "$LINE"      | grep -oP 'result=\[.*?\]' | cut -d'=' -f2)

      echo "$vec_size,$valtype,$encrypt_ms,$total_ms,$bytes,$result" >> $OUTPUT_FILE

      rm $TMP1 $TMP2 $TMP3

      # Give the server time to reset the session before the next trial
      sleep 1

    done
  done
done

echo "Done. Results saved to $OUTPUT_FILE"