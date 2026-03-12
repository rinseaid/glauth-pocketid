package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// TimeWindow represents a single time restriction window
type TimeWindow struct {
	StartHour   int
	StartMinute int
	EndHour     int
	EndMinute   int
	Days        []time.Weekday // empty means all days
}

// ParseTimeWindows parses a time window specification string.
// Format: "HH:MM-HH:MM" or "HH:MM-HH:MM,Mon-Fri"
// Multiple windows separated by semicolons: "09:00-17:00,Mon-Fri;00:00-23:59,Sat-Sun"
// Day ranges: Mon-Fri, Sat-Sun, or individual days: Mon,Wed,Fri
func ParseTimeWindows(spec string) ([]TimeWindow, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}

	parts := strings.Split(spec, ";")
	var windows []TimeWindow

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		tw, err := parseSingleWindow(part)
		if err != nil {
			return nil, fmt.Errorf("parsing window %q: %w", part, err)
		}
		windows = append(windows, tw)
	}

	return windows, nil
}

func parseSingleWindow(spec string) (TimeWindow, error) {
	var tw TimeWindow

	// Split time part from optional day part.
	// The time range is "HH:MM-HH:MM". Days come after a comma following the time range.
	// We need to find the time range first: look for the pattern HH:MM-HH:MM
	// The first comma after the time range separates days.
	// Time range always has the form NN:NN-NN:NN so we can split on the hyphen
	// between the two times. Find the hyphen that separates start and end times:
	// it's the one that comes after the first colon.

	// Strategy: find the first "-" that appears after a ":" — that's the time separator.
	colonIdx := strings.Index(spec, ":")
	if colonIdx < 0 {
		return tw, fmt.Errorf("invalid time format, expected HH:MM-HH:MM")
	}

	// The hyphen separating start and end time comes after "HH:MM"
	timeSepIdx := strings.Index(spec[colonIdx:], "-")
	if timeSepIdx < 0 {
		return tw, fmt.Errorf("invalid time format, expected HH:MM-HH:MM")
	}
	timeSepIdx += colonIdx

	startTimeStr := strings.TrimSpace(spec[:timeSepIdx])

	// Now find where the end time ends. The end time is followed by either
	// end-of-string or a comma introducing the day spec.
	rest := spec[timeSepIdx+1:]

	// The end time is "HH:MM". Find the next comma that is not part of the time.
	// End time ends at the first comma after we've seen the second colon.
	endTimeStr := rest
	daySpec := ""

	secondColon := strings.Index(rest, ":")
	if secondColon < 0 {
		return tw, fmt.Errorf("invalid time format, expected HH:MM-HH:MM")
	}

	// After "HH:MM" (secondColon + 3 if minutes are 2 digits), look for comma
	afterEndTime := rest[secondColon:]
	commaIdx := strings.Index(afterEndTime, ",")
	if commaIdx >= 0 {
		globalComma := timeSepIdx + 1 + secondColon + commaIdx
		endTimeStr = strings.TrimSpace(spec[timeSepIdx+1 : globalComma])
		daySpec = strings.TrimSpace(spec[globalComma+1:])
	} else {
		endTimeStr = strings.TrimSpace(rest)
	}

	// Parse start time
	sh, sm, err := parseHHMM(startTimeStr)
	if err != nil {
		return tw, fmt.Errorf("invalid start time %q: %w", startTimeStr, err)
	}
	tw.StartHour = sh
	tw.StartMinute = sm

	// Parse end time
	eh, em, err := parseHHMM(endTimeStr)
	if err != nil {
		return tw, fmt.Errorf("invalid end time %q: %w", endTimeStr, err)
	}
	tw.EndHour = eh
	tw.EndMinute = em

	// Parse days if present
	if daySpec != "" {
		days, err := parseDaySpec(daySpec)
		if err != nil {
			return tw, fmt.Errorf("invalid day spec %q: %w", daySpec, err)
		}
		tw.Days = days
	}

	return tw, nil
}

func parseHHMM(s string) (int, int, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("expected HH:MM format")
	}

	h, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil || h < 0 || h > 23 {
		return 0, 0, fmt.Errorf("invalid hour %q", parts[0])
	}

	m, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil || m < 0 || m > 59 {
		return 0, 0, fmt.Errorf("invalid minute %q", parts[1])
	}

	return h, m, nil
}

// parseDaySpec handles both ranges (Mon-Fri) and individual days (Mon,Wed,Fri)
// or combinations thereof.
func parseDaySpec(spec string) ([]time.Weekday, error) {
	var days []time.Weekday
	seen := make(map[time.Weekday]bool)

	parts := strings.Split(spec, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if strings.Contains(part, "-") {
			expanded, err := expandDayRange(part)
			if err != nil {
				return nil, err
			}
			for _, d := range expanded {
				if !seen[d] {
					seen[d] = true
					days = append(days, d)
				}
			}
		} else {
			d, err := parseDayName(part)
			if err != nil {
				return nil, err
			}
			if !seen[d] {
				seen[d] = true
				days = append(days, d)
			}
		}
	}

	return days, nil
}

// parseDayName converts a short day name to time.Weekday (case-insensitive).
func parseDayName(s string) (time.Weekday, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "sun":
		return time.Sunday, nil
	case "mon":
		return time.Monday, nil
	case "tue":
		return time.Tuesday, nil
	case "wed":
		return time.Wednesday, nil
	case "thu":
		return time.Thursday, nil
	case "fri":
		return time.Friday, nil
	case "sat":
		return time.Saturday, nil
	default:
		return 0, fmt.Errorf("unknown day name %q", s)
	}
}

// expandDayRange expands a day range like "Mon-Fri" into individual weekdays.
func expandDayRange(spec string) ([]time.Weekday, error) {
	parts := strings.SplitN(spec, "-", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid day range %q", spec)
	}

	start, err := parseDayName(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid start day in range %q: %w", spec, err)
	}

	end, err := parseDayName(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid end day in range %q: %w", spec, err)
	}

	var days []time.Weekday
	current := start
	for {
		days = append(days, current)
		if current == end {
			break
		}
		current = (current + 1) % 7
	}

	return days, nil
}

// IsWithinWindow checks if the given time falls within any of the time windows.
// If windows is empty or nil, returns true (no restriction).
func IsWithinWindow(windows []TimeWindow, now time.Time) bool {
	if len(windows) == 0 {
		return true
	}

	for _, w := range windows {
		if matchesWindow(w, now) {
			return true
		}
	}

	return false
}

func matchesWindow(w TimeWindow, now time.Time) bool {
	// Convert current time and window boundaries to minutes since midnight
	nowMinutes := now.Hour()*60 + now.Minute()
	startMinutes := w.StartHour*60 + w.StartMinute
	endMinutes := w.EndHour*60 + w.EndMinute

	if startMinutes <= endMinutes {
		// Normal window: e.g. 09:00-17:00
		// Day check: current day must be in allowed days
		if !dayAllowed(w, now.Weekday()) {
			return false
		}
		return nowMinutes >= startMinutes && nowMinutes <= endMinutes
	}

	// Midnight-crossing window: e.g. 22:00-06:00
	// The window spans two calendar days. The "start day" owns the pre-midnight
	// portion (>= start), and the day AFTER the start day owns the post-midnight
	// portion (<= end).
	//
	// Example: "22:00-06:00,Mon-Fri"
	//   - Monday 23:00: nowMinutes >= startMinutes, day=Monday (in Mon-Fri) → allow
	//   - Tuesday 02:00: nowMinutes <= endMinutes, yesterday=Monday (in Mon-Fri) → allow
	//   - Saturday 02:00: nowMinutes <= endMinutes, yesterday=Friday (in Mon-Fri) → allow
	//   - Saturday 23:00: nowMinutes >= startMinutes, day=Saturday (NOT in Mon-Fri) → deny
	if nowMinutes >= startMinutes {
		// Pre-midnight portion: current day must be allowed
		return dayAllowed(w, now.Weekday())
	}
	if nowMinutes <= endMinutes {
		// Post-midnight portion: YESTERDAY must be allowed (the window started yesterday)
		yesterday := (now.Weekday() + 6) % 7 // weekday - 1, wrapping Sunday→Saturday
		return dayAllowed(w, yesterday)
	}
	return false
}

// dayAllowed checks if the given weekday is in the window's day list.
// If the window has no day restriction (empty Days), all days are allowed.
func dayAllowed(w TimeWindow, day time.Weekday) bool {
	if len(w.Days) == 0 {
		return true
	}
	for _, d := range w.Days {
		if d == day {
			return true
		}
	}
	return false
}
