#!/bin/bash
# Install Julia version 1.8.2

wget https://julialang-s3.julialang.org/bin/linux/x64/1.8/julia-1.8.2-linux-x86_64.tar.gz
tar -xzf julia-1.8.2-linux-x86_64.tar.gz
sudo mv julia-1.8.2/ /opt/
sudo ln -s /opt/julia-1.8.2/bin/julia /usr/local/bin/julia
rm julia-1.8.2-linux-x86_64.tar.gz
julia gitpod/installMEV.jl
sudo cp gitpod/verify.sh /usr/local/bin/verify
sudo cp gitpod/verifyurl.sh /usr/local/bin/verifyurl
sudo cp gitpod/verifypilot.sh /usr/local/bin/verifypilot
sudo chmod a+x /usr/local/bin/verify /usr/local/bin/verifyurl /usr/local/bin/verifypilot
cat gitpod/welcome


