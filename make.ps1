$IMG="ghcr.io/eiymba/gitpod-eks-guide:latest"

$SECRET=$(Select-String -Path "./.env" "IMAGE_PULL_SECRET_FILE=" | Select-Object -First 1).line -Split "=" | Select-Object -Last 1
$IMAGE_PULL_SECRET

if ($SECRET) {

    $IMAGE_PULL_SECRET= "-v $($(Get-ChildItem .env).FullName)):/gitpod/config.json"
}

function build {
    npm run build
    docker build -f Dockerfile -t $IMG .
}

function DOCKER_RUN_CMD([string]$1) {
    
    docker run --rm -it `
        --env-file ${PWD}\.env `
        -e NODE_ENV=production `
        -v ${PWD}\.kubeconfig:/gitpod/.kubeconfig `
        $IMAGE_PULL_SECRET
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

function auth {
    echo "Installing auth providers...."
    DOCKER_RUN_CMD("--auth")
}

function help {
    Write-Host 'Usage:'
    Write-Host -nonewline './make.ps1 '; Write-Host '<target>' -ForegroundColor cyan
    Write-Host 'build           ' -ForegroundColor cyan -nonewline; Write-Host 'Build docker image containing the required tools for the installation'
    Write-Host 'install         ' -ForegroundColor cyan -nonewline; Write-Host 'Install Gitpod'
    Write-Host 'uninstall       ' -ForegroundColor cyan -nonewline; Write-Host 'Uninstall Gitpod'
    Write-Host 'help            ' -ForegroundColor cyan -nonewline; Write-Host 'Display this help'
}

Switch($args[0]){
    'install' { install }
    'build' { build }
    'uninstall' { uninstall }
    'help' { help }
    '' { help }
}

