# Opsgenie Scripts

## Introduction

This document describes the creation and usage of two Python scripts designed for managing silences in Opsgenie notifications. These scripts help the team create and delete silences on demand, ensuring efficient alert management during maintenance periods or other specified times.

## Notification Policy Overview

A notification policy in Opsgenie defines how alerts are handled for a team. It includes rules for when and how notifications should be suppressed, escalated, or closed. In this setup, the notification policy is configured to suppress notifications for alerts tagged with `"silence"` and automatically close them within one minute, the minimum possible time.

## Create Silence with Python Script

### Step-by-Step Explanation

1. **Define Conditions**

   **Mandatory:**
   - `Customer`

   **Optional:**
   - `Environment`
   - `Query` (matches in alert name or job name)

2. **Duration Input**

   The duration for the silence is specified using the following suffixes:
   - `h` for hours
   - `d` for days
   - `w` for weeks

3. **Utilize Existing Notification Policy**

   A pre-configured notification policy is already established where alerts tagged with `"silence"` will have notifications suppressed permanently and will auto-close after one minute.

4. **Script Logic**

   The script creates a global alert policy based on the defined conditions. The global alert policy:
   - Adds the `"silence"` tag to matching alerts.
   - Appends `" - SILENCE"` to the alert message.

5. **Handle Maintenance Periods**

   Since alert policies in Opsgenie have scheduling options limited to one week, maintenance mode is utilized for flexible scheduling.

   The script schedules a maintenance mode that enables the alert policy for the desired period using full calendar availability.

   After the maintenance period ends, the maintenance mode is canceled, and the alert policy is disabled.

### Script Workflow

- **User Input:** The user provides the conditions (`customer`, `environment`, `query`) and the duration.
- **Global Alert Policy Creation:** The script generates a global alert policy that inserts the `"silence"` tag and updates the alert message.
- **Maintenance Mode Scheduling:** The script schedules a maintenance mode to enable the alert policy for the specified time.
- **Post-Maintenance:** After the scheduled time, the maintenance mode ends, and the alert policy is disabled.

## Delete Silence with Python Script

### Step-by-Step Explanation

1. **Define Conditions**

   **Mandatory:**
   - `Customer`

   **Optional:**
   - `Environment`
   - `Query`

2. **Script Logic**

   The script searches for policies and associated maintenance modes that match the provided conditions and performs the following actions:

   - Cancels the maintenance mode.
   - Deletes the corresponding alert policy.

3. **History Tracking**

   While policies are deleted, descriptions of past maintenance modes are retained for historical reference.

### Script Workflow

- **User Input:** The user provides the conditions (`customer`, `environment`, `query`).
- **Policy and Maintenance Search:** The script identifies policies and maintenance modes based on the conditions.
- **Cleanup Actions:** The script cancels the maintenance mode and deletes the associated alert policy.
- **History:** Descriptions of past maintenance modes are retained for future reference.

## Running the Scripts

### API Key Requirement

To run these scripts, you need an Opsgenie API key. The API key is provided to both scripts using the `-k` flag.

### Example Commands

To create a silence:

```bash
python create_silence.py -k YOUR_OPSGENIE_API_KEY -c CUSTOMER -e ENVIRONMENT -q QUERY -d DURATION
