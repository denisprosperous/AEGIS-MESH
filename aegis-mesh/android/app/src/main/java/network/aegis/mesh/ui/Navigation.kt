package network.aegis.mesh.ui

import androidx.compose.runtime.Composable
import androidx.navigation.NavType
import androidx.navigation.compose.*
import androidx.navigation.navArgument
import network.aegis.mesh.ui.screen.*

object Routes {
    const val ONBOARDING = "onboarding"
    const val PEER_LIST = "peers"
    const val CHAT = "chat/{peerId}"
    const val CHANNEL_LIST = "channels"
    const val CHANNEL_CHAT = "channel_chat/{channelId}"
    const val SETTINGS = "settings"
    const val SCAN = "scan"

    fun chat(peerId: String) = "chat/$peerId"
    fun channelChat(channelId: String) = "channel_chat/$channelId"
}

@Composable
fun AegisNavGraph(startDestination: String = Routes.ONBOARDING) {
    val nav = rememberNavController()
    NavHost(navController = nav, startDestination = startDestination) {
        composable(Routes.ONBOARDING) { OnboardingScreen(nav) }
        composable(Routes.PEER_LIST) { PeerListScreen(nav) }
        composable(
            Routes.CHAT,
            arguments = listOf(navArgument("peerId") { type = NavType.StringType }),
        ) { entry ->
            ChatScreen(
                nav,
                peerId = entry.arguments?.getString("peerId") ?: "",
            )
        }
        composable(Routes.CHANNEL_LIST) { ChannelListScreen(nav) }
        composable(
            Routes.CHANNEL_CHAT,
            arguments = listOf(navArgument("channelId") { type = NavType.StringType }),
        ) { entry ->
            ChannelChatScreen(
                nav,
                channelId = entry.arguments?.getString("channelId") ?: "",
            )
        }
        composable(Routes.SETTINGS) { SettingsScreen(nav) }
        composable(Routes.SCAN) { ScanScreen(nav) }
    }
}
