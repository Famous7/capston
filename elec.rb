# Band Example 2
# Mehackit 2016

use_bpm 120
notes = [70, 70, 70, 80,80, 90,90, 90,90, 90]
durations = [0.25, 0.25, 0.25, 1.5, 0.25, 0.25, 0.25, 0.25, 0.25, 0.25]
set :continueplay,1 # set a dummy value (not 0 or 1 for continueplay, to start with)


live_loop :rummut do
  sample :drum_heavy_kick
  sleep 1
  sample :drum_snare_hard
  sleep 1
  sample :drum_heavy_kick
  sleep 1
  sample :drum_snare_hard
  sleep 1
end

live_loop :hihat do
  sample :drum_cymbal_closed
  sleep 0.25
  sample :drum_cymbal_pedal
  sleep 1
end

live_loop :basso do
  use_synth :tb303
  play chord(:C2, :major).choose, release: 0.125, cutoff: rrand(60, 110)
  sleep 0.25
end

live_loop :melodia do
  use_synth [:hoover, :tech_saws].choose
  if get(:continueplay) == 2
  end

  if one_in(6)
    use_transpose 2
  else
    use_transpose 0
  end
  play_pattern_timed notes, durations, attack: 0, release: 0.2
end


live_loop :notes do
  use_real_time
  data = sync "/osc/notes"
  notes = data
end
