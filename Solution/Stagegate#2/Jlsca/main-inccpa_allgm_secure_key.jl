using Distributed
@everywhere using Jlsca.Sca
@everywhere using Jlsca.Trs
@everywhere using Jlsca.Align    
using Plots

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

plot(getSamples(trs,1))

popSamplePass(trs)

# how much we are willing to move to find an optimum correlation with the reference
maxShift = 100
# where you want the reference to be placed in the result. Setting this to 1 will place it at the beginning.
referenceOffset = 2000
# how long the reference is
referenceLength = 2000
# the reference data itself. Can come from anywhere, but here we extract it from one of traces
reference = trs[1][2][referenceOffset:referenceOffset+referenceLength-1]
# drop traces that correlate less than this minimum
corvalMin = 0.87
# use the FFTW correlator with the above settings
alignstate = CorrelationAlignFFT(reference, referenceOffset, maxShift)
# caches the shift and correlation values, so that in a given process it's only computed once for each trace
alignpass = AlignPass(alignstate, length(trs), corvalMin)
nothing
empty!(trs.meta.passes)
addSamplePass(trs, alignpass)




addSamplePass(trs, x -> x[1000:8000])


numberOfTraces = length(trs)
if length(ARGS) > 1
  numberOfTraces = min(parse(ARGS[2]), numberOfTraces)
end



@time ret = sca(DistributedTrace(getTrs), params, 1, numberOfTraces)


