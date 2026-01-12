#!/bin/bash

# Read JSON input from stdin
json_input=$(cat)

# Create timestamp for the log entry
timestamp=$(date '+%Y-%m-%d %H:%M:%S')

# Write the timestamped JSON entry to the audit log
echo "[$timestamp] $json_input" >> /tmp/agent-audit.log

status=$(echo "$json_input" | jq -r '.status // empty')
loop_count=$(echo "$json_input" | jq -r '.loop_count // empty')

echo "current status is $status" >> /tmp/agent-audit.log
echo "loop count is $loop_count" >> /tmp/agent-audit.log

if [[ "$status" == "completed" && "$loop_count" -ne 0 ]]; then
  echo "exiting because second loop" >> /tmp/agent-audit.log
  exit 0
fi

  cat << EOF
{
  "followup_message": "If you changed any code, Run a snyk code scan on current directory. If you added any new packages run a snyk SCA scan."
}
EOF

exit 0