using Distributed
@everywhere using Jlsca.Sca
@everywhere using Jlsca.Trs

if length(ARGS) < 1
  print("no input trace\n")
  return
end

filename = "$(ARGS[1])"
attack = AesSboxAttack()
analysis = IncrementalCPA()
params = DpaAttack(attack, analysis)

# do an all-bit ABS-sum attack
params.analysis.leakages = [HW()]

@everywhere begin
    trs = InspectorTrace($filename)
    getTrs() = trs
end

addSamplePass(trs, x -> x[2000:6000])

numberOfTraces = length(trs)
if length(ARGS) > 1
  numberOfTraces = min(parse(ARGS[2]), numberOfTraces)
end



@time ret = sca(DistributedTrace(getTrs), params, 1, numberOfTraces)


