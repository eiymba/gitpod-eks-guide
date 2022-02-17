$IMG="ghcr.io/eiymba/gitpod-eks-guide:latest"

function build {
    npm run build
    docker build -f Dockerfile -t $IMG .
}

function DOCKER_RUN_CMD([string]$1) {
    
    docker run --rm -it `
        --env-file ${PWD}\.env `
        -e NODE_ENV=production `
        -v ${PWD}\.kubeconfig:/gitpod/.kubeconfig `
        -v ${PWD}\eks-cluster.yaml:/gitpod/eks-cluster.yaml `
        -v ${PWD}\gitpod-config.yaml:/gitpod/gitpod-config.yaml `
        -v ${PWD}\logs:/root/.npm/_logs `
        -v ${PWD}\cdk-outputs.json:/gitpod/cdk-outputs.json `
        -v ${HOME}\.aws:/root/.aws `
        $IMG $1
}

function install {

    echo "Starting install process..."
	touch ${PWD}\.kubeconfig
    if (-not(Test-Path -Path "${PWD}\gitpod-config.yaml" -PathType Leaf)) {
	    touch ${PWD}\gitpod-config.yaml
    }
	touch ${PWD}\cdk-outputs.json
	DOCKER_RUN_CMD("--install")

}

function uninstall {

    echo "Starting uninstall process..."
	DOCKER_RUN_CMD("--uninstall")

}

Switch($args[0]){
    'install' { install }
    'build' { build }
    'uninstall' { uninstall }
}