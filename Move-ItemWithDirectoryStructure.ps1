<#
.Synopsis
   Move-ItemWithDirectoryStructure
.DESCRIPTION
   Moves files/items recursive out of an directory structure to a new location.
   The existing folder structure will be kept in the destination.

   Assume you want to move all playlists from a music dir to a new location.
   The folder structure in the new location should be the same as in source, but
   there only playlist-files should be placed there. 

.EXAMPLE
   Move-ItemWithDirectoryStructure -Path 'D:\Music' -Destination 'D:\PlayLists' -Filter '*.m3u'

.EXAMPLE
   Move-ItemWithDirectoryStructure -Path 'D:\Music' -Destination 'D:\PlayLists' -Filter '*.m3u' -PassThru

.EXAMPLE
   Move-ItemWithDirectoryStructure -Path 'D:\Music' -Destination 'D:\PlayLists' -Filter '*.m3u' -Verbose

.EXAMPLE
   Move-ItemWithDirectoryStructure -Path 'D:\Music' -Destination 'D:\PlayLists' -Filter '*.m3u' -Verbose -PassThru
#>
function Move-ItemWithDirectoryStructure {
Param(
    [Parameter(Mandatory=$true,
               ValueFromPipelineByPropertyName=$true,
               Position=0,
               HelpMessage="Source path")]
    [ValidateScript({Test-Path -Path $_})]
    [Alias('Source')]
        [String]$Path, 

    [Parameter(Mandatory=$true,
               ValueFromPipelineByPropertyName=$false,
               Position=1,
               HelpMessage="Destination path where item are moved to")]
    [ValidateScript({Test-Path -Path (split-path $_)})]
        [String]$Destination = "D:\PlayLists", 

    [Parameter(Mandatory=$true,
               ValueFromPipelineByPropertyName=$false,
               Position=2,
               HelpMessage="Filter string example: *.m3u")]
    [ValidateNotNullOrEmpty()]
        [String]$Filter = "*",
    
    [Parameter(Mandatory=$false)]
        [Switch]$PassThru
)

    $items = Get-ChildItem -Path $Path -Filter $Filter -Recurse 
    
    if($PSBoundParameters.Verbose) {
        $maxlength = (($items | Group-Object DirectoryName -NoElement | Sort-Object count -Descending)[0].count).ToString().Length
        Write-Verbose "File-Report:"
        $items | Group-Object DirectoryName -NoElement | Select-Object @{n="Output";e={"{0,$maxlength} files in $($_.Name)" -f $($_.Count)}} | Select-Object -ExpandProperty output | Write-Verbose
    }

    foreach($item in $Items) { 
        $destinationDirName = $item.DirectoryName.Replace($Path, $Destination)
        if(-not (Test-Path $destinationDirName)) {
            $destinationDir = New-Item -Path $destinationDirName -ItemType Directory 
        }
        Move-Item -Path $item.FullName -Destination $destinationDirName -Verbose:$(if($PSBoundParameters.Verbose){$true}else{$false}) -PassThru:$(if($PSBoundParameters.PassThru){$true}else{$false}) 
    }
}


