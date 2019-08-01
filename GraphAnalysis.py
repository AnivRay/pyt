import os
import traceback

import Analyzer


def main():
    """
    for (dirname, dirs, files) in os.walk("C:\\Users\\anivr\\Desktop\\AutoDownloadNew"):
        for file in files:
            if str(file).endswith("py"):
                try:
                    taint_analyzer = Analyzer.Analyzer()
                    taint_analyzer.http_finder(dirname + "\\" + file)
                    with open("VulnerabilityResults2.txt", "a+") as outFile:
                        outFile.write(dirname + "\\" + file + "\n")
                        with open("VulnerabilityResultsTemp.txt") as readFile:
                            outFile.write(readFile.read())
                    del taint_analyzer
                except Exception:
                    print("There was an error: " + str(Exception))
    """
    '''
    folders = []
    for (dirname, dirs, files) in os.walk("C:\\Users\\anivr\\Desktop\\AutoDownload"):
        folders = dirs
        for x, f in enumerate(folders):
            folders[x] = dirname + "\\" + f
        break
    for folder in folders:
        print("FOLDER : " + folder)
        print("===================================")
        try:
            taint_analyzer = Analyzer.Analyzer()
            taint_analyzer.main(folder)
            with open("VulnerabilityResults.txt", "a+") as outFile:
                with open("VulnerabilityResultsTemp.txt") as readFile:
                    outFile.write(readFile.read())
            # print(str(taint_analyzer.S / (taint_analyzer.S + taint_analyzer.F)))
            del taint_analyzer
        except Exception as err:
            print("There was an error : " + "[" + str(folder) + "]" + str(err))
            traceback.print_exc()
    '''
    taint_analyzer = Analyzer.Analyzer()
    # taint_analyzer.main("C:\\Users\\anivr\\Desktop\\AutoDownload\\plugin.programm.xbmcmail-0.1.0\\plugin.programm.xbmcmail")
    taint_analyzer.main("C:\\Users\\anivr\\Desktop\\AutoDownload\\xbmc-mailnotifier-0.2.10\\xbmc-mailnotifier-0.2.10")
    # taint_analyzer.main("C:\\Users\\anivr\\Desktop\\AutoDownloadNew\\weather.metoffice\\src\\metoffice\\utilities.py")
    # taint_analyzer.main("C:\\Users\\anivr\\Desktop\\AutoDownload\\weather.yahoo\\default.py")
    # taint_analyzer.main("C:\\Users\\anivr\\Desktop\\AutoDownload\\service.autosubs")
    # found something
    # taint_analyzer.main("C:\\Users\\anivr\\Desktop\\AutoDownload\\plugin.program.utorrent")
    # taint_analyzer.main("C:\\Users\\anivr\\Desktop\\AutoDownload\\service.subtitles.opensubtitles")
    # taint_analyzer.http_finder(C:\Users\anivr\Desktop\AutoDownload\service.subtitles.supersubtitles)
    # no vulnerabilities
    # taint_analyzer.main("C:\\Users\\anivr\\Desktop\\AutoDownload\\script.tv.show.last.episode")
    # error
    # taint_analyzer.main("C:\\Users\\anivr\\Desktop\\AutoDownload\\plugin.video.espn_3")
    # taint_analyzer.main("C:\\Users\\anivr\\Desktop\\AutoDownload\\plugin.video.nasa")
    # taint_analyzer.main("C:\\Users\\anivr\\Desktop\\AutoDownload\\plugin.video.vimeo")
    # taint_analyzer.main("C:\\Users\\anivr\\Desktop\\AutoDownload\\script.maps.browser")
    # taint_analyzer.main("C:\\Users\\anivr\\Desktop\\AutoDownload\\service.subtitles.supersubtitles")
    # taint_analyzer.main("C:\\Users\\anivr\\Desktop\\AutoDownload\\service.subtitles.legendastv")
    # taint_analyzer.main("C:\\Users\\anivr\\Desktop\\AutoDownload\\service.subtitles.divxplanet")
    # taint_analyzer.main("C:\\Users\\anivr\\Desktop\\AutoDownload\\service.subtitles.bsplayer")
    # taint_analyzer.main("C:\\Users\\anivr\\Desktop\\AutoDownload\\script.web.viewer")
    # taint_analyzer.main("C:\\Users\\anivr\\Desktop\\AutoDownload\\script.cinema.experience")
main()
